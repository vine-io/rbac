// MIT License
//
// Copyright (c) 2023 Lack
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package adapter

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"gorm.io/gorm"
)

// GormAdapter represents the Gorm adapter for policy storage.
type GormAdapter struct {
	tablePrefix string
	tableName   string
	db          *gorm.DB
	isFiltered  bool
}

// NewGormAdapter is the constructor for Adapter.
func NewGormAdapter(db *gorm.DB) (*GormAdapter, error) {
	conn, err := db.DB()
	if err != nil {
		return nil, err
	}

	if err = conn.Ping(); err != nil {
		return nil, err
	}

	a := &GormAdapter{db: db}
	a.tableName = (&Rule{}).TableName()
	err = db.AutoMigrate(&Rule{})
	if err != nil {
		return nil, err
	}

	return a, nil
}

// getTableInstance return the dynamic table name
func (a *GormAdapter) getTableInstance() *Rule {
	return &Rule{}
}

func (a *GormAdapter) getFullTableName() string {
	if a.tablePrefix != "" {
		return a.tablePrefix + "_" + a.tableName
	}
	return a.tableName
}

func (a *GormAdapter) ruleTable() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		tableName := a.getFullTableName()
		return db.Table(tableName)
	}
}

func (a *GormAdapter) createTable() error {

	t := a.getTableInstance()
	if err := a.db.AutoMigrate(t); err != nil {
		return err
	}

	tableName := a.getFullTableName()
	index := strings.ReplaceAll("idx_"+tableName, ".", "_")
	hasIndex := a.db.Migrator().HasIndex(t, index)
	if !hasIndex {
		if err := a.db.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (ptype,v0,v1,v2,v3,v4,v5)", index, tableName)).Error; err != nil {
			return err
		}
	}
	return nil
}

func (a *GormAdapter) dropTable() error {

	t := a.getTableInstance()
	if err := a.db.Migrator().DropTable(t); err != nil {
		return err
	}

	return nil
}

// LoadPolicy loads policy from database.
func (a *GormAdapter) LoadPolicy(model model.Model) error {
	var lines []Rule
	if err := a.db.Order("ID").Find(&lines).Error; err != nil {
		return err
	}
	err := a.Preview(&lines, model)
	if err != nil {
		return err
	}
	for _, line := range lines {
		err := loadPolicyLine(line, model)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *GormAdapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var lines []Rule

	batchFilter := BatchFilter{
		filters: []Filter{},
	}
	switch filterValue := filter.(type) {
	case Filter:
		batchFilter.filters = []Filter{filterValue}
	case *Filter:
		batchFilter.filters = []Filter{*filterValue}
	case []Filter:
		batchFilter.filters = filterValue
	case BatchFilter:
		batchFilter = filterValue
	case *BatchFilter:
		batchFilter = *filterValue
	default:
		return errors.New("unsupported filter type")
	}

	for _, f := range batchFilter.filters {
		if err := a.db.Scopes(a.filterQuery(a.db, f)).Order("ID").Find(&lines).Error; err != nil {
			return err
		}

		for _, line := range lines {
			err := loadPolicyLine(line, model)
			if err != nil {
				return err
			}
		}
	}
	a.isFiltered = true

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *GormAdapter) IsFiltered() bool {
	return a.isFiltered
}

// filterQuery builds the gorm query to match the rule filter to use within a scope.
func (a *GormAdapter) filterQuery(db *gorm.DB, filter Filter) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if len(filter.PType) > 0 {
			db = db.Where("ptype in (?)", filter.PType)
		}
		if len(filter.V0) > 0 {
			db = db.Where("v0 in (?)", filter.V0)
		}
		if len(filter.V1) > 0 {
			db = db.Where("v1 in (?)", filter.V1)
		}
		if len(filter.V2) > 0 {
			db = db.Where("v2 in (?)", filter.V2)
		}
		if len(filter.V3) > 0 {
			db = db.Where("v3 in (?)", filter.V3)
		}
		if len(filter.V4) > 0 {
			db = db.Where("v4 in (?)", filter.V4)
		}
		if len(filter.V5) > 0 {
			db = db.Where("v5 in (?)", filter.V5)
		}
		return db
	}
}

func (a *GormAdapter) savePolicyLine(ptype string, rule []string) Rule {
	line := a.getTableInstance()

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return *line
}

// SavePolicy saves policy to database.
func (a *GormAdapter) SavePolicy(model model.Model) error {
	if err := a.dropTable(); err != nil {
		return err
	}

	err := a.createTable()
	if err != nil {
		return err
	}

	var lines []Rule
	flushEvery := 1000
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := a.db.Create(&lines).Error; err != nil {
					return err
				}
				lines = nil
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := a.db.Create(&lines).Error; err != nil {
					return err
				}
				lines = nil
			}
		}
	}
	if len(lines) > 0 {
		if err := a.db.Create(&lines).Error; err != nil {
			return err
		}
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *GormAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.db.Create(&line).Error
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *GormAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.rawDelete(a.db, line) //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
	return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *GormAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []Rule
	for _, rule := range rules {
		line := a.savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	return a.db.Create(&lines).Error
}

// Transaction perform a set of operations within a transaction
func (a *GormAdapter) Transaction(e casbin.IEnforcer, fc func(casbin.IEnforcer) error, opts ...*sql.TxOptions) (err error) {
	oriAdapter := a.db
	// reload policy from database to sync with the transaction
	defer func() {
		e.SetAdapter(&GormAdapter{db: oriAdapter})
		err = e.LoadPolicy()
	}()
	copyDB := *a.db
	tx := copyDB.Begin(opts...)
	b := &GormAdapter{db: tx}
	// copy enforcer to set the new adapter with transaction tx
	copyEnforcer := e
	copyEnforcer.SetAdapter(b)
	err = fc(copyEnforcer)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}
	return nil
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *GormAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.db.Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			line := a.savePolicyLine(ptype, rule)
			if err := a.rawDelete(tx, line); err != nil { //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
				return err
			}
		}
		return nil
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *GormAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := a.getTableInstance()

	line.PType = ptype

	if fieldIndex == -1 {
		return a.rawDelete(a.db, *line)
	}

	err := checkQueryField(fieldValues)
	if err != nil {
		return err
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err = a.rawDelete(a.db, *line)
	return err
}

func (a *GormAdapter) rawDelete(db *gorm.DB, line Rule) error {
	queryArgs := []interface{}{line.PType}

	queryStr := "ptype = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	args := append([]interface{}{queryStr}, queryArgs...)
	err := db.Delete(a.getTableInstance(), args...).Error
	return err
}

// UpdatePolicy updates a new policy rule to DB.
func (a *GormAdapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newPolicy)
	return a.db.Model(&oldLine).Where(&oldLine).Updates(newLine).Error
}

func (a *GormAdapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	oldPolicies := make([]Rule, 0, len(oldRules))
	newPolicies := make([]Rule, 0, len(oldRules))
	for _, oldRule := range oldRules {
		oldPolicies = append(oldPolicies, a.savePolicyLine(ptype, oldRule))
	}
	for _, newRule := range newRules {
		newPolicies = append(newPolicies, a.savePolicyLine(ptype, newRule))
	}
	tx := a.db.Begin()
	for i := range oldPolicies {
		if err := tx.Model(&oldPolicies[i]).Where(&oldPolicies[i]).Updates(newPolicies[i]).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

func (a *GormAdapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// UpdateFilteredPolicies deletes old rules and adds new rules.
	line := a.getTableInstance()

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]Rule, 0, len(newPolicies))
	oldP := make([]Rule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, a.savePolicyLine(ptype, newRule))
	}

	tx := a.db.Begin()
	str, args := line.queryString()
	if err := tx.Where(str, args...).Find(&oldP).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Where(str, args...).Delete([]Rule{}).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	for i := range newP {
		if err := tx.Create(&newP[i]).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, tx.Commit().Error
}

// Preview Pre-checking to avoid causing partial load success and partial failure deep
func (a *GormAdapter) Preview(rules *[]Rule, model model.Model) error {
	j := 0
	for i, rule := range *rules {
		r := []string{rule.PType,
			rule.V0, rule.V1, rule.V2,
			rule.V3, rule.V4, rule.V5}
		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		index += 1
		p := r[:index]
		key := p[0]
		sec := key[:1]
		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return err
		}
		if ok {
			(*rules)[j], (*rules)[i] = rule, (*rules)[j]
			j++
		}
	}
	*rules = (*rules)[j:]
	return nil
}
